package jwt

import (
	"encoding/base64"
	"errors"
	"fmt"
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
	headerB64, err := t.Header.ToBase64()
	if err != nil {
		return nil, err
	}
	payloadB64, err := t.Payload.ToBase64()
	if err != nil {
		return nil, err
	}

	headerPayloadCompact := fmt.Sprintf("%s.%s", headerB64, payloadB64)
	algorithm := t.Header.Properties["alg"].(AlgorithmType)

	tokenType, err := DetermineTokenType(algorithm)
	if err != nil {
		return nil, err
	}

	switch tokenType {
	case JWS:
		signer := Signer{
			Token:    t,
			SignFunc: getSignFunc(algorithm),
		}

		signedBytes, err := signer.Sign([]byte(headerPayloadCompact))
		if err != nil {
			return nil, err
		}

		signatureB64 := base64.RawURLEncoding.EncodeToString(signedBytes)

		return []byte(fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64)), nil
	case JWE:
		log.Fatal("JWE Not Implemented")
	}

	return nil, errors.New("unable to encode - please check algorithm")
}