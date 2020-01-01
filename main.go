package main

import (
	"fmt"
	"github.com/bmwadforth/jwt/src"
	"log"
)

//JWS and JWE are 'implementations' of JWT
//For example, JWS is a 'signed' JWT


func main(){
	claims := make(map[string]interface{})
	claims["aud"] = "Brannon"
	token, err := src.Build("HS256", claims, []byte("THIS_IS_A_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(token))
	//token, err := Jwt.Parse()
}
