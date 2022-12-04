package adapter

import (
	"net/http"
	"time"
)

type TokenCookie struct {
	expireAfter         time.Duration
	tokenIdentifierName string
	idTokenName         string
}

func NewTokenCookie(expireAfter time.Duration,
	tokenIdentifierName, idTokenName string) *TokenCookie {

	return &TokenCookie{
		expireAfter:         expireAfter,
		tokenIdentifierName: tokenIdentifierName,
		idTokenName:         idTokenName,
	}
}

func set(w http.ResponseWriter, sameSiteMode http.SameSite, name, value string, expireAfter time.Duration, maxAge int) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		SameSite: sameSiteMode,
		Path:     "/",
		Expires:  time.Now().Add(expireAfter),
		MaxAge:   maxAge,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
}

func get(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (a *TokenCookie) GetTokenIdentifier(r *http.Request) string {
	return get(r, a.tokenIdentifierName)
}

func (a *TokenCookie) SetTokenIdentifier(w http.ResponseWriter, tokenIdentifier string) {
	set(w, http.SameSiteStrictMode, a.tokenIdentifierName, tokenIdentifier, a.expireAfter, 0)
}

func (a *TokenCookie) GetIDToken(r *http.Request) string {
	return get(r, a.idTokenName)
}

func (a *TokenCookie) SetIDToken(w http.ResponseWriter, idToken string) {
	set(w, http.SameSiteStrictMode, a.idTokenName, idToken, a.expireAfter, 0)
}
