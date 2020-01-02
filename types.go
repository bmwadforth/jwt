package jwt

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

type SignFunc func(bytes []byte, key []byte) ([]byte, error)

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

type TokenType string

const (
	JWS TokenType = "jws"
	JWE TokenType = "jwe"
)

type AlgorithmType string

const (
	Custom AlgorithmType = "CUSTOM"

	HS256 AlgorithmType = "HS256"
	None  AlgorithmType = "none"

	//TODO: JWE
)

type Header struct {
	Properties map[string]interface{}
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

type Signer struct {
	*Token
	SignFunc
}

