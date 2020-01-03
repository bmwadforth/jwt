package jwt

import (
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestEncodeRSA256(t *testing.T) {
	key, _ := ioutil.ReadFile("./private.pem")
	claims := NewClaimSet()
	err := claims.Add(string(Audience), "developers"); if err != nil {
		t.Fatal(err)
	}

	token, err := New(RS256, claims, key); if err != nil {
		t.Fatal(err)
	}

	encodedBytes, err := token.Encode(); if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(encodedBytes))
}

func TestDecodeRSA256(t *testing.T) {
	key, _ := ioutil.ReadFile("./private.pem")
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.JGIY1LNLHrE0HOw9gySdFY3M7Kaw4htBLcXg5M-ym8qhOYRx-n2tLDHBBo778QWJ0uAL9lbWFTw8_9P82i5reXEia9V4OOqtw3mCaYWpe0yTK4l7tb6Ed9MbK0_Z_evJPRRfVc-fPbYeeQ4AibAiwtUZUi0-b5e2EUtbt8CeIqouH3hz0MTkPJjGrvGjbkBLhziUR6g2yXBNWi4-eq-WzUb38OgW2xcwh10farJIVFtjjUparytECB2PnzDZjM5_aOyw8WmI5LEMBpHjDMSsgx41MyE1MlmrOjAnBsL8X156tmKgmH-AHqHmKC99YPThwfxwIe9P2Ey-OSsnnC0Hmw"

	token, err := Parse(tokenString, key); if err != nil {
		t.Fatal(err)
	}

	if token.Claims[string(Audience)] != "developers" {
		t.Fatal(errors.New("claims not decoded correctly"))
	}
}

func TestValidateRSA256(t *testing.T){
	key, _ := ioutil.ReadFile("./private.pem")
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZXZlbG9wZXJzIn0.JGIY1LNLHrE0HOw9gySdFY3M7Kaw4htBLcXg5M-ym8qhOYRx-n2tLDHBBo778QWJ0uAL9lbWFTw8_9P82i5reXEia9V4OOqtw3mCaYWpe0yTK4l7tb6Ed9MbK0_Z_evJPRRfVc-fPbYeeQ4AibAiwtUZUi0-b5e2EUtbt8CeIqouH3hz0MTkPJjGrvGjbkBLhziUR6g2yXBNWi4-eq-WzUb38OgW2xcwh10farJIVFtjjUparytECB2PnzDZjM5_aOyw8WmI5LEMBpHjDMSsgx41MyE1MlmrOjAnBsL8X156tmKgmH-AHqHmKC99YPThwfxwIe9P2Ey-OSsnnC0Hmw"

	token, err := Parse(tokenString, key); if err != nil {
		t.Fatal(err)
	}

	_, err = Validate(token); if err != nil {
		t.Fatal(err)
	}
}