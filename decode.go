package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func (t *Token) decodeHS256() (*Token, error){
	if t.output == nil {
		return t, errors.New("base64 encoded jwt must be supplied to be decoded")
	}

	tokenComponents := strings.Split(string(t.output), ".")

	headerJson, _ := base64.RawURLEncoding.DecodeString(tokenComponents[0])
	payloadJson, _ := base64.RawURLEncoding.DecodeString(tokenComponents[1])

	_ = json.Unmarshal(headerJson, &t.Header)
	_ = json.Unmarshal(payloadJson, &t.Payload.Claims)

	return t, nil
}