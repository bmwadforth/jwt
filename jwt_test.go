package jwt

import (
	"bytes"
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

	token, err := Parse(tokenString)
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims["aud"] != "everyone" {
		t.Fatal("unable to decode jwt string correctly")
	}
}

func TestValidateJWT(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJldmVyeW9uZSJ9.NFs_ovvcxQG1PszLUNXmierwLVEK3-mHq5SGKr3DOXw"

	token, err := Parse(tokenString)
	if err != nil {
		t.Fatal(err)
	}

	key := []byte("THIS_IS_A_KEY")
	isValid, _ := token.Validate(key)

	if !isValid {
		t.Fatal("token is not valid")
	}
}

func TestCustomJWSSign(t *testing.T) {
	token, err := New(HS256, NewClaimSet(), []byte("KEY"))
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(token, func(b []byte, key []byte) ([]byte, error) {
		buff := bytes.Buffer{}
		buffer := bytes.NewBuffer(buff.Bytes())

		buffer.Write(b)
		buffer.Write(key)

		return buffer.Bytes(), nil
	})

	if err != nil {
		t.Fatal(err)
	}

	signedBytes, _ := signer.Sign([]byte("BYTES"))

	if !bytes.Equal(signedBytes, []byte{66, 89, 84, 69, 83, 75, 69, 89}) {
		t.Fatal("signer function returned invalid bytes")
	}
}