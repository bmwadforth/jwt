package jwt

//All logic for encoding a JWT will be performed here by creating receivers on the JWT Struct
//This includes, encryption and signing the contents of the JWT header, payload and trailer - and base64 encoding them.

func (t *Token) encode() ([]byte, error){
	//1. Marshall header and payload into JSON object
	//2. Base64 encode JSON object
	//3. Perform Signature generation steps
	//4. Return bytes

	return nil, nil
}