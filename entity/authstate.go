package entity

import "time"

var (
	NilAuthState = AuthState{}
)

type AuthState struct {
	State     string     `gorm:"primaryKey;type:string;size:1024" json:"state,omitempty"`
	CreatedAt *time.Time `gorm:"<-:create" json:"created_at,omitempty"`
	UpdatedAt *time.Time `gorm:"<-" json:"updated_at,omitempty"`

	CodeVerifier  string `gorm:"type:string;size:1024" json:"code_verifier,omitempty"`
	AuthRequestID string `gorm:"type:string;size:1024" json:"auth_request_id,omitempty"`
}
