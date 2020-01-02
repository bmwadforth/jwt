package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func getSignFunc(a AlgorithmType) SignFunc {
	switch a {
	case HS256:
		return signHMAC256
	case None:
		return func(_ []byte, _ []byte) ([]byte, error) {
			return nil, nil
		}
	}

	return nil
}

func signHMAC256(d []byte, key []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(d)
	return mac.Sum(nil), nil
}

func (s *Signer) Sign(bytesToSign []byte) ([]byte, error) {
	if s.SignFunc == nil {
		return nil, errors.New("unable to sign data without a signing function defined")
	}

	signedBytes, err := s.SignFunc(bytesToSign, s.Token.key)
	if err != nil {
		return nil, err
	}

	return signedBytes, nil
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