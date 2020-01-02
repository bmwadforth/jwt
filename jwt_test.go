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

	err = claims.Add(string(Subject), "everyone")
	if err != nil {
		t.Fatal(err)
	}

	err = claims.Add("usr", "brannon")
	if err != nil {
		t.Fatal(err)
	}

	token, _ := New("HS256", claims, []byte("THIS_IS_A_KEY"))

	tokenBytes, err := token.Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(tokenBytes))
}

func TestDecodeJWT(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJldmVyeW9uZSIsInN1YiI6ImV2ZXJ5b25lIiwidXNyIjoiYnJhbm5vbiJ9"

	token, err := Parse(tokenString)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%+v\n", token)
}

