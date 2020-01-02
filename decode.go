package jwt

import (
	"errors"
	"strings"
)

func (t *Token) Decode()  error {
	if t.raw == nil || string(t.raw) == "" {
		return errors.New("raw token string must be provided to decode")
	}

	tokenComponents := strings.Split(string(t.raw), ".")

	header, _ := t.Header.FromBase64([]byte(tokenComponents[0]))
	t.Header = *header

	payload, _ := t.Payload.FromBase64([]byte(tokenComponents[1]))
	t.Payload = *payload

	return nil
}
