package jwt

import (
	"encoding/base64"
	"encoding/json"
)

//Serialize header struct into JSON
func (h *Header) ToJson() ([]byte, error){
	jsonBytes, err := json.Marshal(h.Properties)
	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

//Serialize header struct into JSON and then Encode in b64
func (h *Header) ToBase64() ([]byte, error){
	jsonBytes, err := h.ToJson()
	if err != nil {
		return nil, err
	}

	b64Bytes := base64.RawURLEncoding.EncodeToString(jsonBytes)

	h.raw = []byte(b64Bytes)

	return []byte(b64Bytes), nil
}

//Deserialize JSON into header struct
func (h *Header) FromJson(b []byte) (*Header, error){
	err := json.Unmarshal(b, &h.Properties)
	if err != nil {
		return nil, err
	}

	return h, nil
}

//Deserialize b64 into JSON and then into header struct
func (h *Header) FromBase64(b []byte) (*Header, error){
	jsonBytes, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &h.Properties)
	if err != nil {
		return nil, err
	}

	return h, nil
}