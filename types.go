package jwt

//Interfaces

//Structs
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
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
