package jwt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestEncodeJWT(t *testing.T) {
	claims := NewClaimSet()
	err := claims.Add(string(Audience), "everyone")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := New(HS256, claims, []byte("THIS_IS_A_KEY"))

	tokenBytes, err := token.Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(tokenBytes))
}

func TestDecodeJWT(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJldmVyeW9uZSJ9.NFs_ovvcxQG1PszLUNXmierwLVEK3-mHq5SGKr3DOXw"

	token, err := Parse(tokenString, []byte("THIS_IS_A_KEY"))
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims["aud"] != "everyone" {
		t.Fatal("unable to decode jwt string correctly")
	}
}

func TestRSA256Sign(t *testing.T) {
	t.Skip()
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	fmt.Println(key)

	token, err := New(RS256, NewClaimSet(), key)

	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := token.Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(tokenBytes))
}

func TestCustomJWSSign(t *testing.T) {
	token, err := New(HS256, NewClaimSet(), []byte("KEY"))
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(token, func(t *Token, signingInput []byte) ([]byte, error) {
		//Signing Input is b64header.b64payload
		return []byte("signed"), nil
	})

	if err != nil {
		t.Fatal(err)
	}

	signedBytes, err := signer.Sign()
	if err != nil {
		t.Fatal(err)
	}

	headerB64, _ := token.Header.ToBase64()
	payloadB64, _ := token.Payload.ToBase64()
	signatureB64 := []byte(base64.RawURLEncoding.EncodeToString([]byte("signed")))

	expectedBytes := fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64)

	if !bytes.Equal(signedBytes, []byte(expectedBytes)) {
		t.Fatal("bytes do not match")
	}
}