package adapter

import (
	"net/http"
)

type NopTokenHeader struct {
}

func NewNopTokenHeader() *NopTokenHeader {

	return &NopTokenHeader{}
}

func (a *NopTokenHeader) GetTokenIdentifier(r *http.Request) string {
	return ""
}

func (a *NopTokenHeader) SetTokenIdentifier(w http.ResponseWriter, tokenIdentifier string) {
}

func (a *NopTokenHeader) GetIDToken(r *http.Request) string {
	return ""
}

func (a *NopTokenHeader) SetIDToken(w http.ResponseWriter, idToken string) {
}
