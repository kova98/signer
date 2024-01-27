package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	key string
}

func NewSigner(signingKey string) *Signer {
	return &Signer{signingKey}
}

func (s *Signer) Sign(model Answer) (string, error) {
	jsonString, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(jsonString)
	return hex.EncodeToString(hash[:]), nil
}

func (s *Signer) ParseSubClaimFromJwt(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.key), nil
	})
	if err != nil {
		return "", err
	}

	return token.Claims.GetSubject()
}
