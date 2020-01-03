package jwt

import "errors"

var jwsAlgorithms = []AlgorithmType{HS256, RS256, ES256, None}

func DetermineTokenType(alg AlgorithmType) (TokenType, error) {
	//TODO: Improve the efficiency of this function, it shouldn't really just loop over a slice and check if the currently
	//iterated element is equal to the argument

	for _, val := range jwsAlgorithms {
		if val == alg {
			return JWS, nil
		}
	}

	//TODO: Range over JWE algorithms

	return "", errors.New("unable to determine token type - check algorithm is supported")
}