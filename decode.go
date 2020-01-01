package jwt

import "errors"

//All logic for decoding a JWT will be performed here by creating receivers on the JWT Struct
//This includes, decryption and signing the contents of the JWT header, payload and trailer - and base64 decoding them.

func (t *Token) decode() (*Token, error){
	if t.Output == nil {
		return t, errors.New("base64 encoded jwt must be supplied to be decoded")
	}

	//output exists,
	//1. base64 decode each component of the jwt
	//2. this will reveal JSON, serialize this back into a model
	//

	return t, nil
}