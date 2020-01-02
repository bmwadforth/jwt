package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

func getSignFunc(a AlgorithmType) SignFunc {
	switch a {
	case HS256:
		return signHMAC256
	case RS256:
		return signRSA256
	case None:
		return func(_ *Token, _ []byte) ([]byte, error) {
			return nil, nil
		}
	}

	return nil
}

func signHMAC256(t *Token, signingInput []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, t.key)
	mac.Write(signingInput)
	signedBytes := mac.Sum(nil)

	return signedBytes, nil
}

func signRSA256(t *Token, signingInput []byte) ([]byte, error) {

	return nil, nil
}

func (s *Signer) Sign() ([]byte, error) {
	if s.SignFunc == nil {
		return nil, errors.New("unable to sign data without a signing function defined")
	}

	headerB64, err := s.Header.ToBase64()
	if err != nil {
		return nil, err
	}

	payloadB64, err := s.Payload.ToBase64()
	if err != nil {
		return nil, err
	}

	signingInput := fmt.Sprintf("%s.%s", headerB64, payloadB64)

	signedBytes, err := s.SignFunc(s.Token, []byte(signingInput))
	if err != nil {
		return nil, err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signedBytes)

	return []byte(fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64)), nil
}

func NewSigner(t *Token, signFunc SignFunc) (*Signer, error){
	if t == nil {
		return nil, errors.New("token structure must be supplied")
	}

	return &Signer{
		Token:    t,
		SignFunc: signFunc,
	}, nil
}