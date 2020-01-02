package jwt

import (
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


