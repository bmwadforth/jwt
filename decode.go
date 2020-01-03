package jwt

import (
	"errors"
	"strings"
)

func (t *Token) Decode() error {
	if t.raw == nil || string(t.raw) == "" {
		return errors.New("raw token string must be provided to decode")
	}

	tokenComponents := strings.Split(string(t.raw), ".")

	_, err := t.Header.FromBase64([]byte(tokenComponents[0]))
	if err != nil {
		return err
	}

	_, err = t.Payload.FromBase64([]byte(tokenComponents[1]))
	if err != nil {
		return err
	}

	t.Signature.Raw = []byte(tokenComponents[2])

	return nil
}
