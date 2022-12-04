package port

import "net/http"

type TokenCookie interface {
	GetTokenIdentifier(r *http.Request) string
	SetTokenIdentifier(w http.ResponseWriter, tokenIdentifier string)

	GetIDToken(r *http.Request) string
	SetIDToken(w http.ResponseWriter, idToken string)

	GetTokenSource(r *http.Request) string
	SetTokenSource(w http.ResponseWriter, tokenSource string)
}
