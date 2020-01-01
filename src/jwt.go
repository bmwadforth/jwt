package src

//This library has been designed and implemented with meticulous reference to rfc7519
/*
This section defines which algorithms and features of this
specification are mandatory to implement.  Applications using this
specification can impose additional requirements upon implementations
that they use.  For instance, one application might require support
for encrypted JWTs and Nested JWTs, while another might require
support for signing JWTs with the Elliptic Curve Digital Signature
Algorithm (ECDSA) using the P-256 curve and the SHA-256 hash
algorithm ("ES256").

Of the signature and MAC algorithms specified in JSON Web Algorithms
[JWA], only HMAC SHA-256 ("HS256") and "none" MUST be implemented by
conforming JWT implementations.  It is RECOMMENDED that
implementations also support RSASSA-PKCS1-v1_5 with the SHA-256 hash
algorithm ("RS256") and ECDSA using the P-256 curve and the SHA-256
hash algorithm ("ES256").  Support for other algorithms and key sizes
is OPTIONAL.

Support for encrypted JWTs is OPTIONAL.  If an implementation
provides encryption capabilities, of the encryption algorithms
specified in [JWA], only RSAES-PKCS1-v1_5 with 2048-bit keys
("RSA1_5"), AES Key Wrap with 128- and 256-bit keys ("A128KW" and
"A256KW"), and the composite authenticated encryption algorithm using
AES-CBC and HMAC SHA-2 ("A128CBC-HS256" and "A256CBC-HS512") MUST be
implemented by conforming implementations.  It is RECOMMENDED that
implementations also support using Elliptic Curve Diffie-Hellman
Ephemeral Static (ECDH-ES) to agree upon a key used to wrap the
Content Encryption Key ("ECDH-ES+A128KW" and "ECDH-ES+A256KW") and
AES in Galois/Counter Mode (GCM) with 128- and 256-bit keys
("A128GCM" and "A256GCM").  Support for other algorithms and key
sizes is OPTIONAL.

Support for Nested JWTs is OPTIONAL.*/

/*
+-------------------+--------------------+
| "alg" Param Value | MAC Algorithm      |
+-------------------+--------------------+
| HS256             | HMAC using SHA-256 |
| HS384             | HMAC using SHA-384 |
| HS512             | HMAC using SHA-512 |
+-------------------+--------------------+
*/

//JOSE Header
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	//Whatever other mandatory fields are go here
}

//Although an interface, the value of each map item needs to conform to JSON grammar - string, array, number, etc.
type Payload struct {
	Claims map[string]interface{}
}

//This token is embedded in the payload of either a JWE or a JWS
type Token struct {
	Header
	Payload
	key []byte
	output []byte
}

func Build(alg string, claims map[string]interface{}, key []byte) ([]byte, error) {
	//Check if alg supplied is in list of 'supported algorithms'

	token := Token{
		Header: Header{
			Algorithm: alg,
			Type: "JWT",
		},
		Payload: Payload{
			Claims: claims,
		},
		key: key,
	}

	//Based on the arguments to the func, return a JWS or a JWE
	return token.encode()
}

func Parse(tokenString string) {
	//token := Token{output: []byte(tokenString)}
	//token.decode()
}
