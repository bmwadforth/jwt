package jwt

import (
	"encoding/base64"
	"encoding/json"
)

//Serialize payload struct into JSON
func (p *Payload) ToJson() ([]byte, error){
	jsonBytes, err := json.Marshal(p.Claims)
	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

//Serialize payload struct into JSON and then Encode in b64
func (p *Payload) ToBase64() ([]byte, error){
	jsonBytes, err := p.ToJson()
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	p.raw = []byte(b64Bytes)

	return []byte(b64Bytes), nil
}

//Deserialize JSON into payload struct
func (p *Payload) FromJson(b []byte) (*Payload, error){
	err := json.Unmarshal(b, &p.Claims)
	if err != nil {
		return nil, err
	}

	return p, nil
}

//Deserialize b64 into JSON and then into payload struct
func (p *Payload) FromBase64(b []byte) (*Payload, error){
	jsonBytes, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &p.Claims)
	if err != nil {
		return nil, err
	}

	return p, nil
}