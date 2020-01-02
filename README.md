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
### Custom Signing Method

If you would prefer to define your own JWS signing method, you can define your own SignFunc

```go
package main

import (
    "fmt"
    . "github.com/bmwadforth/jwt"
)

func main(){
    token, _ := New(HS256, NewClaimSet(), []byte("Key")) 
    signer, _ := NewSigner(token, func(b []byte, key []byte) ([]byte, error) {
        //key is automatically populated with the key argument when creating the token
        //b is the bytes to sign
        //Implement your own HS256 signing logic here
        return nil, nil
    })
    signedBytes, _ := signer.Sign([]byte(""))
    
    fmt.Println(string(signedBytes))
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
   | RS256        | RSASSA-PKCS1-v1_5 using SHA-256                | Recommended        | ❌|
   | RS384        | RSASSA-PKCS1-v1_5 using SHA-384        | Optional           | ❌|
   | RS512        | RSASSA-PKCS1-v1_5 using SHA-512        | Optional           | ❌|
   | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       | ❌|
   | ES384        | ECDSA using P-384 and SHA-384 | Optional           | ❌|
   | ES512        | ECDSA using P-521 and SHA-512 | Optional           | ❌|
   | PS256        | RSASSA-PSS using SHA-256 and MGF1 with SHA-256      | Optional           | ❌|
   | PS384        | RSASSA-PSS using SHA-384 and MGF1 with SHA-384     | Optional           | ❌|
   | PS512        | RSASSA-PSS using SHA-512 and MGF1 with SHA-512   | Optional           | ❌|
   | none         | No digital signature or MAC performed    | Optional           | ✅|
   
   
#### JWE

**_JWE has not been implemented in this library yet_**
<!---
| "alg" Param        | Key Management Algorithm  | Header Params|  Implementation Requirement |
| ------------- |:-------------:| -----:| -----:|
| RSA1_5             | RSAES-PKCS1-v1_5   | (none) | Recommended-   |
   | RSA-OAEP           | RSAES OAEP using   | (none) | Recommended+   |
   |                    | default parameters |        |                |
   | RSA-OAEP-256       | RSAES OAEP using   | (none) | Optional       |
   |                    | SHA-256 and MGF1   |        |                |
   |                    | with SHA-256       |        |                |
   | A128KW             | AES Key Wrap with  | (none) | Recommended    |
   |                    | default initial    |        |                |
   |                    | value using        |        |                |
   |                    | 128-bit key        |        |                |
   | A192KW             | AES Key Wrap with  | (none) | Optional       |
   |                    | default initial    |        |                |
   |                    | value using        |        |                |
   |                    | 192-bit key        |        |                |
   | A256KW             | AES Key Wrap with  | (none) | Recommended    |
   |                    | default initial    |        |                |
   |                    | value using        |        |                |
   |                    | 256-bit key        |        |                |
   | dir                | Direct use of a    | (none) | Recommended    |
   |                    | shared symmetric   |        |                |
   |                    | key as the CEK     |        |                |
   | ECDH-ES            | Elliptic Curve     | "epk", | Recommended+   |
   |                    | Diffie-Hellman     | "apu", |                |
   |                    | Ephemeral Static   | "apv"  |                |
   |                    | key agreement      |        |                |
   |                    | using Concat KDF   |        |                |
   | ECDH-ES+A128KW     | ECDH-ES using      | "epk", | Recommended    |
   |                    | Concat KDF and CEK | "apu", |                |
   |                    | wrapped with       | "apv"  |                |
   |                    | "A128KW"           |        |                |
   | ECDH-ES+A192KW     | ECDH-ES using      | "epk", | Optional       |
   |                    | Concat KDF and CEK | "apu", |                |
   |                    | wrapped with       | "apv"  |                |
   |                    | "A192KW"           |        |                |
   | ECDH-ES+A256KW     | ECDH-ES using      | "epk", | Recommended    |
   |                    | Concat KDF and CEK | "apu", |                |
   |                    | wrapped with       | "apv"  |                |
   |                    | "A256KW"           |        |                |
   | A128GCMKW          | Key wrapping with  | "iv",  | Optional       |
   |                    | AES GCM using      | "tag"  |                |
   |                    | 128-bit key        |        |                |
   | A192GCMKW          | Key wrapping with  | "iv",  | Optional       |
   |                    | AES GCM using      | "tag"  |                |
   |                    | 192-bit key        |        |                |
   | A256GCMKW          | Key wrapping with  | "iv",  | Optional       |
   |                    | AES GCM using      | "tag"  |                |
   |                    | 256-bit key        |        |                |
   | PBES2-HS256+A128KW | PBES2 with HMAC    | "p2s", | Optional       |
   |                    | SHA-256 and        | "p2c"  |                |
   |                    | "A128KW" wrapping  |        |                |
   | PBES2-HS384+A192KW | PBES2 with HMAC    | "p2s", | Optional       |
   |                    | SHA-384 and        | "p2c"  |                |
   |                    | "A192KW" wrapping  |        |                |
   | PBES2-HS512+A256KW | PBES2 with HMAC    | "p2s", | Optional       |
   |                    | SHA-512 and        | "p2c"  |                |
   |                    | "A256KW" wrapping  |        |                |
   ---!>