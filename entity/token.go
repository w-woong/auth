package entity

import "time"

var (
	NilToken = Token{}
)

type TokenSource string

var (
	TokenSourceWoong  TokenSource = "woong"
	TokenSourceGoogle TokenSource = "google"
)

type Token struct {
	ID        string     `gorm:"primaryKey;type:string;size:64;comment:id" json:"id,omitempty"`
	CreatedAt *time.Time `gorm:"<-:create" json:"created_at,omitempty"`
	UpdatedAt *time.Time `gorm:"<-" json:"updated_at,omitempty"`

	TokenSource  TokenSource `gorm:"uniqueIndex:idx_tokens_1;type:string;size:32" json:"token_source,omitempty"`
	AccessToken  string      `gorm:"uniqueIndex:idx_tokens_1;type:string" json:"access_token,omitempty"`
	RefreshToken string      `gorm:"type:string" json:"refresh_token,omitempty"`
	TokenType    string      `gorm:"type:string;size:32" json:"token_type,omitempty"`
	IDToken      string      `gorm:"type:string" json:"id_token,omitempty"`
	Expiry       int64       `gorm:"type:int" json:"expiry,omitempty"`
}
