# Json Web Token (RFC7519) Library

### Mission
This library has two goals.
* Make generating and validating _JWTs_ as intuitive and easy as possible, with the ability to add complexity if the developer chooses
* Follow RFC7519 and implement the recommended cryptographic algorithms for both JWS and JWE

### Disclaimer
This library is extremely **new**. Integrate it with your applications at your own risk. Notably, the library could rapidly change in design - causing breaking changes. 

### Quickstart
If all you want to do is generate and validate a JWT, use these examples.

#### Generating a HS256 JWT
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

    //Create new HS256 token, set claims and key
    token, err := New(HS256, claims, key)
    if err != nil {
        log.Fatal(err)
    }

    //Encode token
    tokenBytes, err := token.Encode()
    fmt.Println(string(tokenBytes))
    //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2F1ZGllbmNlIiwiaWF0IjoiMjAyMC0wMS0wMlQyMTo1NTo1OS40MzE1ODErMTE6MDAiLCJteV9jbGFpbSI6InNvbWVfdmFsdWUiLCJzdWIiOiJ5b3VyX3N1YmplY3QifQ.PAR_a60R6VZakCmBZg8aMgt3eXDi-CMC4P4p08yJy-I
}
```

#### Validating a HS256 JWT
```go
package main

import (
    "fmt"
    . "github.com/bmwadforth/jwt"
    "log"
)

func main(){
    key := []byte("Key")
    tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2F1ZGllbmNlIiwiaWF0IjoiMjAyMC0wMS0wMlQyMTo1NTo1OS40MzE1ODErMTE6MDAiLCJteV9jbGFpbSI6InNvbWVfdmFsdWUiLCJzdWIiOiJ5b3VyX3N1YmplY3QifQ.PAR_a60R6VZakCmBZg8aMgt3eXDi-CMC4P4p08yJy-I"
    
    //Parse token string
    token, err := Parse(tokenString, key)
    if err != nil {
        log.Fatal(err)
    }
    
    //Validate token
    _, err = Validate(token)
    if err != nil {
        log.Fatal(err)
    }   
    
    //Token is valid
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
    b, _ := ioutil.ReadFile("./rsa_private.pem")

    block, _ := pem.Decode(b)
    key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

    token, err := New(RS256, NewClaimSet(), block.Bytes)
    if err != nil {
        log.Fatal(err)
    }

    //Before calling validate, set SignFunc
    token.SignFunc = func(t *Token, signingInput []byte) (bytes []byte, e error) {
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
    }

    signedBytes, err := token.Sign()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(signedBytes))
    //eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.uZTBWMOdIYMlSxyJgGOgjPXwISnMDzLyiOE5k9GK2ruWc2IvWkOLtmZ9ECOwDqwLM93WH7CMIP7IEOMVZJzkHkFj16GgQnz-KSgY9MK8fBROij4R09XyXVRMvmBjVAyPxBS8dK9j-FuZIceu5TEN3-FmjcTq87OQfc3-mO6_3mruQfg59m9dSbcVL2SEQrRyrG-Jitkma7f_up8BSJHt0Q08ASVBivHjws2Z_QGYb3NkrI0oEcH_yoXlvJohsEQtNaycFLGNDtzujABHp9ZT5a2L-U8WCf8K9JwttGnuVTMhDviEjWC2M2weXAB8WimiwqQB2zER-4ILpbUhhL_MjA
}
```

### Custom Validation Method

Just as you can create a custom signing method, you can also create a custom validation method.

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
    "encoding/base64"
)

func main(){
    b, _ := ioutil.ReadFile("./rsa_private.pem")
    block, _ := pem.Decode(b)
    key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

    tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.uZTBWMOdIYMlSxyJgGOgjPXwISnMDzLyiOE5k9GK2ruWc2IvWkOLtmZ9ECOwDqwLM93WH7CMIP7IEOMVZJzkHkFj16GgQnz-KSgY9MK8fBROij4R09XyXVRMvmBjVAyPxBS8dK9j-FuZIceu5TEN3-FmjcTq87OQfc3-mO6_3mruQfg59m9dSbcVL2SEQrRyrG-Jitkma7f_up8BSJHt0Q08ASVBivHjws2Z_QGYb3NkrI0oEcH_yoXlvJohsEQtNaycFLGNDtzujABHp9ZT5a2L-U8WCf8K9JwttGnuVTMhDviEjWC2M2weXAB8WimiwqQB2zER-4ILpbUhhL_MjA"

    token, err := Parse(tokenString, b)
    if err != nil {
        log.Fatal(err)
    }

    //Before calling validate, set ValidateFunc
    token.ValidateFunc = func(t *Token) (b bool, e error) {
        headerB64, _ := t.Header.ToBase64()
        payloadB64, _ := t.Payload.ToBase64()
        hashed := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", headerB64, payloadB64)))
        decodedSignature, err := base64.RawURLEncoding.DecodeString(string(t.Signature.Raw))
        if err != nil {
            return false, err
        }
        err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], decodedSignature)
        if err != nil {
            return false, err
        }
        return true, nil
    }

    _, err = token.Validate()
    if err != nil {
        log.Fatal(err)
    }

    //Token is valid
}
```

### Supported Algorithms
This library currently supports JWS only.


#### JWS
| "alg" Param        | Digital Signature/MAC Algorithm           | Implementation Requirement  | Implemented  |
| ------------- |:-------------:| -----:| -----:|
| HS256        | HMAC using SHA-256            | Required           | ✅ |
   | HS384        | HMAC using SHA-384            | Optional           |❌ |
   | HS512        | HMAC using SHA-512            | Optional           |❌ |
   | RS256        | RSASSA-PKCS1-v1_5 using SHA-256                | Recommended        | ✅|
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