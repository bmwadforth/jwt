package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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
	block, _ := pem.Decode(t.key)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	rng := rand.Reader
	hashed := sha256.Sum256(signingInput)

	signature, err := rsa.SignPKCS1v15(rng, key, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (s *Signer) Sign() ([]byte, error) {
	if s.SignFunc == nil {
		return nil, errors.New("unable to sign data without a signing function defined")
	}

	//Header and payload haven't been base64 encoded, so let's do it
	if len(s.Header.raw) == 0 && len(s.Payload.raw) == 0 {
		_, err := s.Header.ToBase64()
		if err != nil {
			return nil, err
		}
		_, err = s.Payload.ToBase64()
		if err != nil {
			return nil, err
		}
	}

	signedBytes, err := s.SignFunc(s.Token, []byte(fmt.Sprintf("%s.%s", s.Header.raw, s.Payload.raw)))
	if err != nil {
		return nil, err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signedBytes)

	return []byte(fmt.Sprintf("%s.%s.%s", s.Header.raw, s.Payload.raw, signatureB64)), nil
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