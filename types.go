package jwt

//Interfaces
/*
//JWS & JWE structs should implement this
type JWX interface {
	Encoder
	Decoder
}*/

type EncoderDecoder interface {
	Encoder
	Decoder
}

type Encoder interface {
	Encode
}

type Encode interface {
	ToJson() ([]byte, error)
	ToBase64() ([]byte, error)
}

type Decoder interface {
	Decode
}

type Decode interface {
	FromJson() (*Encoder, error)
	FromBase64() (*Encoder, error)
}

//Type Definitions
type RegisteredClaim string
const (
	Issuer         RegisteredClaim = "iss"
	Subject        RegisteredClaim = "sub"
	Audience       RegisteredClaim = "aud"
	ExpirationTime RegisteredClaim = "exp"
	NotBefore      RegisteredClaim = "nbf"
	IssuedAt       RegisteredClaim = "iat"
	JwtID          RegisteredClaim = "jti"
)

//Data Structures
type Header struct {
	Properties map[string]interface{}
	//Algorithm string `json:"alg"`
	//Type      string `json:"typ"`
}

type ClaimSet struct {
	Claims map[string]interface{}
}

type Payload struct {
	ClaimSet
}

type Signature struct {
}

type Token struct {
	Header
	Payload
	Signature
	key []byte
	raw []byte
}
