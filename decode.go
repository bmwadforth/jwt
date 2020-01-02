package jwt

import (
	"errors"
	"log"
	"strings"
)

func (t *Token) Decode()  (bool, error) {
	if t.raw == nil || string(t.raw) == "" {
		return false, errors.New("raw token string must be provided to decode")
	}

	tokenComponents := strings.Split(string(t.raw), ".")

	header, _ := t.Header.FromBase64([]byte(tokenComponents[0]))
	t.Header = *header

	payload, _ := t.Payload.FromBase64([]byte(tokenComponents[1]))
	t.Payload = *payload

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
