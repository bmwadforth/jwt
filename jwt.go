package jwt

import (
	"errors"
	"log"
)

func New(alg AlgorithmType, claims ClaimSet, key []byte) (*Token, error) {
	//TODO: Validate Algorithm here, should be one of supported JWE/JWS algs
	//if invalid alg, return nil, errors.New("a supported algorithm must be provided")
	token := Token{
		Header: Header{
			Properties: map[string]interface{}{
				"alg": alg,
				"typ": "JWT",
			},
			raw: []byte{},
		},
		Payload: Payload{
			ClaimSet: claims,
			raw: []byte{},
		},
		Signature: Signature{},
		key: key,
		raw: []byte{},
	}

	return &token, nil
}

func Parse(tokenString string, key []byte) (*Token, error) {
	token := Token{raw: []byte(tokenString)}
	token.key = key

	err := token.Decode()
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func Validate(t *Token) (bool, error){
	algorithm, ok := t.Header.Properties["alg"].(AlgorithmType); if !ok {
		algorithmStr, ok := t.Header.Properties["alg"].(string); if ok {
			algorithm = AlgorithmType(algorithmStr)
		}
	}

	tokenType, err := DetermineTokenType(algorithm)
	if err != nil {
		return false, err
	}

	switch tokenType {
	case JWS:
		validator, err := NewValidator(t, getValidateFunc(algorithm))
		if err != nil {
			log.Fatal(err)
		}

		return validator.Validate()
	case JWE:
		log.Fatal("JWE Not Implemented")
	default:
		//TODO: If you get here, CUSTOM has been chosen for the algorithm, which means the developer consuming this API will be implementing the SignFunc/EncryptFunc
	}

	return false, errors.New("unable to decode - please check algorithm")
}