package dto

import "time"

var NilToken = Token{}

type Token struct {
	ID        string     `json:"tid,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`

	TokenSource  string `json:"token_source,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Expiry       int64  `json:"expiry,omitempty"`
}

func (d *Token) HideSensitive() *Token {
	d.AccessToken = ""
	d.RefreshToken = ""
	// d.Expiry = 0
	d.TokenType = ""
	return d
}
