# Json Web Token (RFC7519) Library

### Mission
This library has two goals.
* Make generating and validating _JWTs_ as intuitive and easy as possible, with the ability to add complexity if the developer chooses
* Follow RFC7519 and implement the recommended cryptographic algorithms for both JWS and JWE

### Disclaimer
This library is extremely **new**. Integrate it with your applications at your own risk. Notably, the library could rapidly change in design - causing breaking changes. 

### Quickstart
If all you want to do is generate and validate a JWT, use these examples.

#### Generating a JWT
```go
package main

import (
    "fmt"
    . "github.com/bmwadforth/jwt"
    "log"
    "time"
)

func main(){
    key := []byte("Key")
    claims := NewClaimSet()
    claims.Add(string(Audience), "your_audience")
    claims.Add(string(Subject), "your_subject")
    claims.Add(string(IssuedAt), time.Now())
    claims.Add("my_claim", "some_value")

    token, err := New(HS256, claims, key)
    if err != nil {
        log.Fatal(err)
    }

    tokenBytes, err := token.Encode()
    fmt.Println(string(tokenBytes))
    //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2F1ZGllbmNlIiwiaWF0IjoiMjAyMC0wMS0wMlQyMTo1NTo1OS40MzE1ODErMTE6MDAiLCJteV9jbGFpbSI6InNvbWVfdmFsdWUiLCJzdWIiOiJ5b3VyX3N1YmplY3QifQ.PAR_a60R6VZakCmBZg8aMgt3eXDi-CMC4P4p08yJy-I
}
```

#### Validating a JWT
```go
package main

import (
    "fmt"
    . "github.com/bmwadforth/jwt"
    "log"
)

func main(){
    tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2F1ZGllbmNlIiwiaWF0IjoiMjAyMC0wMS0wMlQyMTo1NTo1OS40MzE1ODErMTE6MDAiLCJteV9jbGFpbSI6InNvbWVfdmFsdWUiLCJzdWIiOiJ5b3VyX3N1YmplY3QifQ.PAR_a60R6VZakCmBZg8aMgt3eXDi-CMC4P4p08yJy-I"
    key := []byte("Key")
    //If the above key was used to generate our tokenString, 
    //parse will deserialize our token string into a token structure
    token, err := Parse(tokenString, key)
    if err != nil {
        log.Fatal(err)
    }

    //No errors, token is valid
    fmt.Println(token.Claims)
}
```

### Custom Signing Method

If you would prefer to define your own JWS signing method, you can define your own signing function.
Notably, there are a few caveats
* Do not call token.Encode() otherwise the signing function will be _overriden_ with the signing function defined by the library for the algorithm supplied
* The signing function will **always** receive a base64 encoded header and payload as the bytes to sign, per the JWS specification

A good example of when you would want to implement your own signing function is when you want more control over how to sign your token. For example, RS256: 

```go
package main

import (
    "fmt"
    . "github.com/bmwadforth/jwt"
    "io/ioutil"
    "log"
    "crypto/x509"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto"
    "encoding/pem"
)

func main(){
    b, _ := ioutil.ReadFile("./rsa_privae.pem")

    block, _ := pem.Decode(b)

    key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

    token, err := New(RS256, NewClaimSet(), block.Bytes)
    if err != nil {
        log.Fatal(err)
    }

    signer, err := NewSigner(token, func(t *Token, signingInput []byte) ([]byte, error) {
        // crypto/rand.Reader is a good source of entropy for blinding the RSA
        // operation.
        rng := rand.Reader

        // Only small messages can be signed directly; thus the hash of a
        // message, rather than the message itself, is signed. This requires
        // that the hash function be collision resistant. SHA-256 is the
        // least-strong hash function that should be used for this at the time
        // of writing (2016).
        hashed := sha256.Sum256(signingInput)

        signature, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, hashed[:])
        if err != nil {
            return nil, err
        }

        return signature, nil
    })

    if err != nil {
        log.Fatal(err)
    }

    signedBytes, err := signer.Sign()
    if err != nil {
        log.Fatal(err)
    }

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