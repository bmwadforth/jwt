package jwt

import (
	"errors"
	"fmt"
)

func NewClaimSet() ClaimSet {
	return ClaimSet{Claims: map[string]interface{}{}}
}

func (c *ClaimSet) Add(key string, value interface{}) error {
	//TODO: Ensure value is of JSON grammar
	_, found := c.Claims[key]; if found {
		return errors.New("duplicate claims are forbidden")
	}

	c.Claims[key] = value

	return nil
}


func (c *ClaimSet) Remove(key string) error {
	_, found := c.Claims[key]; if found {
		delete(c.Claims, key)
	} else {
		return errors.New(fmt.Sprintf("key: %s was not found in claim set", key))
	}

	return nil
}
