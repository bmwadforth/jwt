package jwt

import "errors"

var jwsAlgorithms = []AlgorithmType{HS256, None}

func DetermineTokenType(alg AlgorithmType) (TokenType, error) {

	for _, val := range jwsAlgorithms {
		if val == alg {
			return JWS, nil
		}
	}

	//TODO: Range over JWE algorithms

	return "", errors.New("unable to determine token type - check algorithm is supported")
}