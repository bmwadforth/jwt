package jwt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
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
	b, _ := ioutil.ReadFile("./private.pem")

	token, err := New(RS256, NewClaimSet(), b)
	if err != nil {
		t.Fatal(err)
	}

	signedBytes, err := token.Encode()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(signedBytes))
}

func TestRSA256Validate(t *testing.T) {
	key, _ := ioutil.ReadFile("./private.pem")
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.uZTBWMOdIYMlSxyJgGOgjPXwISnMDzLyiOE5k9GK2ruWc2IvWkOLtmZ9ECOwDqwLM93WH7CMIP7IEOMVZJzkHkFj16GgQnz-KSgY9MK8fBROij4R09XyXVRMvmBjVAyPxBS8dK9j-FuZIceu5TEN3-FmjcTq87OQfc3-mO6_3mruQfg59m9dSbcVL2SEQrRyrG-Jitkma7f_up8BSJHt0Q08ASVBivHjws2Z_QGYb3NkrI0oEcH_yoXlvJohsEQtNaycFLGNDtzujABHp9ZT5a2L-U8WCf8K9JwttGnuVTMhDviEjWC2M2weXAB8WimiwqQB2zER-4ILpbUhhL_MjA"

	token, err := Parse(tokenString, key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(token.Claims)
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