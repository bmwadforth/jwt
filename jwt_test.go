package jwt

import (
	"fmt"
	"testing"
)

func TestJWT(t *testing.T) {
	claims := ClaimSet{Claims: map[string]interface{}{}}
	err := claims.Add("aud", "everyone")
	if err != nil {
		t.Fatal(err)
	}

	token, err := New("HS256", claims, []byte("THIS_IS_A_KEY"))

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(token))
}
