package jwt

import (
	"errors"
	"log"
)


/*
   When validating a JWT, the following steps are performed.  The order
   of the steps is not significant in cases where there are no
   dependencies between the inputs and outputs of the steps.  If any of
   the listed steps fail, then the JWT MUST be rejected -- that is,
   treated by the application as an invalid input.

   1.   Verify that the JWT contains at least one period ('.')
        character.

   2.   Let the Encoded JOSE Header be the portion of the JWT before the
        first period ('.') character.

   3.   Base64url decode the Encoded JOSE Header following the
        restriction that no line breaks, whitespace, or other additional
        characters have been used.

   4.   Verify that the resulting octet sequence is a UTF-8-encoded
        representation of a completely valid JSON object conforming to
        RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.

   5.   Verify that the resulting JOSE Header includes only parameters
        and values whose syntax and semantics are both understood and
        supported or that are specified as being ignored when not
        understood.

   6.   Determine whether the JWT is a JWS or a JWE using any of the
        methods described in Section 9 of [JWE].

   7.   Depending upon whether the JWT is a JWS or JWE, there are two
        cases:

        *  If the JWT is a JWS, follow the steps specified in [JWS] for
           validating a JWS.  Let the Message be the result of base64url
           decoding the JWS Payload.

        *  Else, if the JWT is a JWE, follow the steps specified in
           [JWE] for validating a JWE.  Let the Message be the resulting
           plaintext.

   8.   If the JOSE Header contains a "cty" (content type) value of
        "JWT", then the Message is a JWT that was the subject of nested
        signing or encryption operations.  In this case, return to Step
        1, using the Message as the JWT.

   9.   Otherwise, base64url decode the Message following the
        restriction that no line breaks, whitespace, or other additional
        characters have been used.

   10.  Verify that the resulting octet sequence is a UTF-8-encoded
        representation of a completely valid JSON object conforming to
        RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object.

   Finally, note that it is an application decision which algorithms may
   be used in a given context.  Even if a JWT can be successfully
   validated, unless the algorithms used in the JWT are acceptable to
   the application, it SHOULD reject the JWT.
*/

func getValidateFunc(a AlgorithmType) ValidateFunc {
	switch a {
	case HS256:
		return validateHMAC256
	case RS256:
		return validateRSA256
	case None:
		return func(_ []byte, _ []byte) (bool, error) {
			return true, nil
		}
	}

	return nil
}

func validateHMAC256(raw []byte, key []byte) (bool, error) {
	log.Fatal("hmac256 validation not implemented")

	return true, nil
}

func validateRSA256(raw []byte, key []byte) (bool, error) {
	log.Fatal("rsa256 validation not implemented")

	return true, nil
}

func (v *Validator) Validate(bytesToValidate []byte) (bool, error) {
	if v.ValidateFunc == nil {
		return false, errors.New("unable to verify data without a validating function defined")
	}

	valid, err := v.ValidateFunc(bytesToValidate, v.key)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func NewValidator(t *Token, validatorFunc ValidateFunc) (*Validator, error){
	if t == nil {
		return nil, errors.New("token structure must be supplied")
	}

	return &Validator{
		Token:    t,
		ValidateFunc: validatorFunc,
	}, nil
}