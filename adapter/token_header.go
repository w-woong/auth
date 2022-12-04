package adapter

import (
	"net/http"
)

type TokenHeader struct {
	tokenIdentifierName string
	idTokenName         string
}

func NewTokenHeader(tokenIdentifierName, idTokenName string) *TokenHeader {

	return &TokenHeader{
		tokenIdentifierName: tokenIdentifierName,
		idTokenName:         idTokenName,
	}
}

func (a *TokenHeader) GetTokenIdentifier(r *http.Request) string {
	return r.Header.Get(a.tokenIdentifierName)
}

func (a *TokenHeader) SetTokenIdentifier(w http.ResponseWriter, tokenIdentifier string) {
	// set(w, http.SameSiteStrictMode, a.tokenIdentifierName, tokenIdentifier, a.expireAfter, 0)
	w.Header().Set(a.tokenIdentifierName, tokenIdentifier)
}

func (a *TokenHeader) GetIDToken(r *http.Request) string {
	return r.Header.Get(a.idTokenName)
}

func (a *TokenHeader) SetIDToken(w http.ResponseWriter, idToken string) {
	w.Header().Set(a.idTokenName, idToken)
}
