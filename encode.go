package jwt

import (
	"errors"
	"log"
)

/*
7.1.  Creating a JWT

   To create a JWT, the following steps are performed.  The order of the
   steps is not significant in cases where there are no dependencies
   between the inputs and outputs of the steps.

   1.  Create a JWT Claims Set containing the desired claims.  Note that
       whitespace is explicitly allowed in the representation and no
       canonicalization need be performed before encoding.

   2.  Let the Message be the octets of the UTF-8 representation of the
       JWT Claims Set.

   3.  Create a JOSE Header containing the desired set of Header
       Parameters.  The JWT MUST conform to either the [JWS] or [JWE]
       specification.  Note that whitespace is explicitly allowed in the
       representation and no canonicalization need be performed before
       encoding.

   4.  Depending upon whether the JWT is a JWS or JWE, there are two
       cases:

       *  If the JWT is a JWS, create a JWS using the Message as the JWS
          Payload; all steps specified in [JWS] for creating a JWS MUST
          be followed.

       *  Else, if the JWT is a JWE, create a JWE using the Message as
          the plaintext for the JWE; all steps specified in [JWE] for
          creating a JWE MUST be followed.

   5.  If a nested signing or encryption operation will be performed,
       let the Message be the JWS or JWE, and return to Step 3, using a
       "cty" (content type) value of "JWT" in the new JOSE Header
       created in that step.

   6.  Otherwise, let the resulting JWT be the JWS or JWE.
*/

func (t *Token) Encode() ([]byte, error){
	_, err := t.Header.ToBase64()
	if err != nil {
		return nil, err
	}

	_, err = t.Payload.ToBase64()
	if err != nil {
		return nil, err
	}

	algorithm, ok := t.Header.Properties["alg"].(AlgorithmType); if !ok {
		algorithmStr, ok := t.Header.Properties["alg"].(string); if ok {
			algorithm = AlgorithmType(algorithmStr)
		}
	}

	tokenType, err := DetermineTokenType(algorithm)
	if err != nil {
		return nil, err
	}

	switch tokenType {
	case JWS:
		return t.Sign()
	case JWE:
		log.Fatal("JWE Not Implemented")
	default:
		//TODO: If you get here, CUSTOM has been chosen for the algorithm, which means the developer consuming this API will be implementing the SignFunc/EncryptFunc
	}

	return nil, errors.New("unable to encode - please check algorithm")
}