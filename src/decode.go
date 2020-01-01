package src

import "errors"

func (t *Token) decode() (*Token, error){
	if t.output == nil {
		return t, errors.New("base64 encoded jwt must be supplied to be decoded")
	}

	//output exists,
	//1. base64 decode each component of the jwt
	//2. this will reveal JSON, serialize this back into a model

	return t, nil
}