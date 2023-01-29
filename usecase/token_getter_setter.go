package usecase

import (
	"net/http"

	"github.com/w-woong/auth/port"
)

type tokenGetter struct {
	cookie port.TokenCookie
	header port.TokenCookie
}

func NewTokenGetter(cookie port.TokenCookie, header port.TokenCookie) *tokenGetter {
	return &tokenGetter{
		cookie: cookie,
		header: header,
	}
}

func (u *tokenGetter) GetTokenIdentifier(r *http.Request) string {
	id := u.cookie.GetTokenIdentifier(r)
	if id != "" {
		return id
	}
	return u.header.GetTokenIdentifier(r)
}

// getIDToken retrieves id_token from cookie or header
func (u *tokenGetter) GetIDToken(r *http.Request) string {
	idToken := u.cookie.GetIDToken(r)
	if idToken != "" {
		return idToken
	}
	return u.header.GetIDToken(r)
}
func (u *tokenGetter) GetTokenSource(r *http.Request) string {
	val := u.cookie.GetTokenSource(r)
	if val != "" {
		return val
	}
	return u.header.GetTokenSource(r)
}

type tokenSetter struct {
	cookie port.TokenCookie
	header port.TokenCookie
}

func NewTokenSetter(cookie port.TokenCookie, header port.TokenCookie) *tokenSetter {
	return &tokenSetter{
		cookie: cookie,
		header: header,
	}
}

func (u *tokenSetter) SetTokenIdentifier(w http.ResponseWriter, val string) {
	u.cookie.SetTokenIdentifier(w, val)
	u.header.SetTokenIdentifier(w, val)
}

func (u *tokenSetter) SetIDToken(w http.ResponseWriter, val string) {
	u.cookie.SetIDToken(w, val)
	u.header.SetIDToken(w, val)
}
func (u *tokenSetter) SetTokenSource(w http.ResponseWriter, val string) {
	u.cookie.SetTokenSource(w, val)
	u.header.SetTokenSource(w, val)
}
