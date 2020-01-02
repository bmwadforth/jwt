package jwt

func New(alg AlgorithmType, claims ClaimSet, key []byte) (*Token, error) {
	//TODO: Validate Algorithm here, should be one of supported JWE/JWS algs
	//if invalid alg, return nil, errors.New("a supported algorithm must be provided")
	token := Token{
		Header: Header{
			Properties: map[string]interface{}{
				"alg": alg,
				"typ": "JWT",
			},
		},
		Payload: Payload{
			ClaimSet: claims,
		},
		Signature: Signature{},
		key: key,
	}

	return &token, nil
}

func Parse(tokenString string) (*Token, error) {
	token := Token{raw: []byte(tokenString)}

	err := token.Decode()
	if err != nil {
		return nil, err
	}

	return &token, nil
}
