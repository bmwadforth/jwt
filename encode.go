package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

func (t *Token) encodeHS256() ([]byte, error){
	headerJson, err := json.Marshal(t.Header)
	if err != nil {
		log.Fatal(err)
	}

	payloadJson, err := json.Marshal(t.ClaimSet)
	if err != nil {
		log.Fatal(err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJson)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJson)

	token := fmt.Sprintf("%s.%s", headerB64, payloadB64)

	signature := hmac.New(sha256.New, t.key)
	signature.Write([]byte(token))

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))

	token = fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64)

	return []byte(token), nil
}