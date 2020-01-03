package jwt

type SignFunc func(t *Token, signingInput []byte) ([]byte, error)
type ValidateFunc func(t *Token) (bool, error)

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
	HS256 AlgorithmType = "HS256"
	ES256 AlgorithmType = "ES256"
	RS256 AlgorithmType = "RS256"
	None  AlgorithmType = "none"

	//TODO: JWE
)

type Header struct {
	Properties map[string]interface{}
	raw []byte
}

type ClaimSet struct {
	Claims map[string]interface{}
}

type Payload struct {
	ClaimSet
	raw []byte
}

type Signature struct {
	Raw []byte
}

type Token struct {
	Header
	Payload
	Signature
	SignFunc
	ValidateFunc
	key []byte
	raw []byte
}
