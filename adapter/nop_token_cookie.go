package adapter

import (
	"net/http"
)

type NopTokenCookie struct {
}

func NewNopTokenCookie() *NopTokenCookie {

	return &NopTokenCookie{}
}

func (a *NopTokenCookie) GetTokenIdentifier(r *http.Request) string {
	return ""
}

func (a *NopTokenCookie) SetTokenIdentifier(w http.ResponseWriter, tokenIdentifier string) {
}

func (a *NopTokenCookie) GetIDToken(r *http.Request) string {
	return ""
}

func (a *NopTokenCookie) SetIDToken(w http.ResponseWriter, idToken string) {
}
