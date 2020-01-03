package jwt

import "errors"

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

//Parsing is slightly different to creating tokens. Parsing will accept the token string and a key.
//After parsing the token string and decoding it, it will validate the token using the key provided
func Parse(tokenString string, key []byte) (*Token, error) {
	token := Token{raw: []byte(tokenString)}
	token.key = key

	valid, err := token.Decode()
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("token is invalid")
	}

	return &token, nil
}
