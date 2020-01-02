package jwt

type SignFunc func(bytes []byte, key []byte) ([]byte, error)
type ValidateFunc func(raw []byte, key []byte) (bool, error)

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

	RS256 AlgorithmType = "RS256"
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

type Validator struct {
	*Token
	ValidateFunc
}
