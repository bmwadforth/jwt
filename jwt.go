package jwt

import (
	"errors"
	"log"
)

/*
This library has been designed and implemented with loose reference to RFC7519
TODO Introduce more algorithm support
	 Implement validation - specifically JSON grammar validation, and algorithm validation
	 Introduce proper error handling - errors shouldn't be log.Fatal'ing
*/

//JOSE Header
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Payload struct {
	Claims map[string]interface{}
}

type Token struct {
	Header
	Payload
	key []byte
	raw []byte
}

func Build(alg string, claims map[string]interface{}, key []byte) ([]byte, error) {
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

	switch alg {
	case "HS256":
		return token.encodeHS256()
	}

	return nil, errors.New("a supported algorithm must be provided")
}

func Parse(tokenString string) (*Token, error) {
	token := Token{raw: []byte(tokenString)}
	t, err := token.decodeHS256()
	if err != nil {
		log.Fatal(err)
	}

	return t, nil
}
